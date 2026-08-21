// `onnx` ConfidentialTransform session component: a confined ONNX inference
// workload, the ML counterpart of `concat`.
//
// Data plane (mirrors the C++ Session lifecycle):
//   * configure(model) : `model` is the raw ONNX model bytes (delivered by the
//                        orchestrator from the ConfigureRequest). We build a
//                        tract runnable plan, fixing the input to a single
//                        1x1x28x28 f32 image (MNIST).
//   * write(image)     : `image` is the input tensor as little-endian f32
//                        (row-major 28x28 = 784 values), already normalized by
//                        the client. Accumulated across calls.
//   * commit()         : no-op.
//   * finalize()       : run inference, argmax the 10 logits, and emit the
//                        predicted digit through the host `context` capability.
//
// The whole model runs inside the wasm sandbox via tract (pure Rust); there is
// no host ML backend and no wasi-nn, so inference happens confined in the TEE.
// tract's std usage lowers to WASI imports (random/clocks), which is exactly
// what the derived capability claim will surface.
#[allow(warnings)]
mod bindings;

use std::cell::RefCell;
use std::io::Cursor;

use bindings::cfc::transform::context::{self, Kv};
use bindings::exports::cfc::transform::session::Guest;
use tract_onnx::prelude::*;

/// MNIST input geometry: one grayscale 28x28 image.
const ROWS: usize = 28;
const COLS: usize = 28;
const PIXELS: usize = ROWS * COLS;

type Plan = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

thread_local! {
    // The compiled inference plan, built in `configure`.
    static MODEL: RefCell<Option<Plan>> = const { RefCell::new(None) };
    // The input tensor bytes accumulated across `write` calls.
    static INPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

struct Component;

impl Guest for Component {
    fn configure(model: Vec<u8>) {
        let plan = tract_onnx::onnx()
            .model_for_read(&mut Cursor::new(&model))
            .expect("parse onnx model")
            // Pin the input to a concrete shape so the model optimizes even if
            // its declared batch dimension is symbolic.
            .with_input_fact(
                0,
                InferenceFact::dt_shape(f32::datum_type(), tvec!(1, 1, ROWS, COLS)),
            )
            .expect("set input fact")
            .into_optimized()
            .expect("optimize model")
            .into_runnable()
            .expect("make runnable");
        MODEL.with(|m| *m.borrow_mut() = Some(plan));
        INPUT.with(|i| i.borrow_mut().clear());
    }

    fn write(data: Vec<u8>) {
        INPUT.with(|i| i.borrow_mut().extend_from_slice(&data));
    }

    fn commit() {}

    fn finalize() {
        let bytes = INPUT.with(|i| i.borrow().clone());
        let pixels: Vec<f32> = bytes
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        assert_eq!(pixels.len(), PIXELS, "expected {PIXELS} f32 pixels, got {}", pixels.len());

        let image: Tensor = tract_ndarray::Array4::from_shape_vec((1, 1, ROWS, COLS), pixels)
            .expect("reshape image")
            .into();

        let output = MODEL.with(|m| {
            let m = m.borrow();
            let plan = m.as_ref().expect("model not configured");
            plan.run(tvec!(image.into())).expect("run inference")
        });

        let scores = output[0].to_array_view::<f32>().expect("read logits");
        let (digit, confidence) = scores
            .iter()
            .cloned()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .expect("non-empty logits");

        // Emit the prediction: [digit: u32 LE][confidence: f32 LE].
        let mut value = Vec::with_capacity(8);
        value.extend_from_slice(&(digit as u32).to_le_bytes());
        value.extend_from_slice(&confidence.to_le_bytes());
        context::emit_unencrypted(&Kv { key: "prediction".to_string(), value });
    }
}

bindings::export!(Component with_types_in bindings);
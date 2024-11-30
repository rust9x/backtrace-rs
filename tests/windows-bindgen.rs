#[test]
#[ignore]
fn bindgen() {
    let args = ["--etc", "bindings.txt"];

    windows_bindgen::bindgen(args).unwrap();
}

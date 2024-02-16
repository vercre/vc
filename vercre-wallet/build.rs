fn main() {
    uniffi::generate_scaffolding("src/shared.udl").expect("should generate scaffolding");
}

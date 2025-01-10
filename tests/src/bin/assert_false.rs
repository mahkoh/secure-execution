use secure_execution::requires_secure_execution;

fn main() {
    assert!(!requires_secure_execution());
    assert!(!requires_secure_execution());
}

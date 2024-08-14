#[test]
fn test_big_multiply() {
    let a: u128 = 1234567890;
    let b: u128 = 9876543210;
    assert_eq!(a * b, 12193263111263526900);
}

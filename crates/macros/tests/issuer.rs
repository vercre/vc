use vercre_macros::create_offer;
use vercre_openid::issuer::{CreateOfferRequest, SendType};

#[test]
fn test() {
    let x = create_offer!({
        "input_1": "input1"
    });
}

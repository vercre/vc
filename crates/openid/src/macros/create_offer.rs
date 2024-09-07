#[macro_export]
#[doc(hidden)]
#[allow(clippy::module_name_repetitions)]
macro_rules! internal_create_offer {

    // ------------------------------------------------------------------------
    // Object TT muncher.
    //
    // Invoked as: internal_create_offer!(@object $map () ($($tt)*) ($($tt)*))
    //
    // It requires two copies of the input tokens so that they can be matched on
    // one copy and trigger errors with the other.
    // ------------------------------------------------------------------------

    // Done.
    (@object $object:ident () () ()) => {};

    (@object $object:ident ["credential_issuer"] ($value:expr) , $($rest:tt)*) => {
        $object.credential_issuer = $value.to_string();
        $crate::internal_create_offer!(@object $object () ($($rest)*) ($($rest)*));
    };

    (@object $object:ident ["credential_configuration_ids"] ($value:expr) , $($rest:tt)*) => {
        $object.credential_configuration_ids = $value;
        $crate::internal_create_offer!(@object $object () ($($rest)*) ($($rest)*));
    };

    (@object $object:ident ["subject_id"] ($value:expr) , $($rest:tt)*) => {
        $object.subject_id = Some($value.to_string());
        $crate::internal_create_offer!(@object $object () ($($rest)*) ($($rest)*));
    };

    (@object $object:ident ["pre-authorize"] (true) , $($rest:tt)*) => {
        $object.pre_authorize = true;
        $crate::internal_create_offer!(@object $object () ($($rest)*) ($($rest)*));
    };

    (@object $object:ident ["pre-authorize"] (false) , $($rest:tt)*) => {
        $object.pre_authorize = false;
        $crate::internal_create_offer!(@object $object () ($($rest)*) ($($rest)*));
    };

    (@object $object:ident ["tx_code_required"] (true) , $($rest:tt)*) => {
        $object.tx_code_required = true;
        $crate::internal_create_offer!(@object $object () ($($rest)*) ($($rest)*));
    };

    (@object $object:ident ["tx_code_required"] (false) , $($rest:tt)*) => {
        $object.tx_code_required = false;
        $crate::internal_create_offer!(@object $object () ($($rest)*) ($($rest)*));
    };

    (@object $object:ident ["send_type"] ($value:expr) , $($rest:tt)*) => {
        $object.send_type = $value;
        $crate::internal_create_offer!(@object $object () ($($rest)*) ($($rest)*));
    };

    // Current entry followed by unexpected token.
    (@object $object:ident [$($key:tt)+] ($value:expr) $unexpected:tt $($rest:tt)*) => {
        $crate::json_unexpected!($unexpected);
    };

    // ------------------------------------------------------------------------
    // @object lookahead functions
    // ------------------------------------------------------------------------
    // Next value is `null`.
    (@object $object:ident ($($key:tt)+) (: null $($rest:tt)*) $copy:tt) => {
        $crate::json_unexpected!($copy);
        // $crate::internal_create_offer!(@object $object [$($key)+] (null) $($rest)*);
    };

    // Next value is `true`.
    (@object $object:ident ($($key:tt)+) (: true $($rest:tt)*) $copy:tt) => {
        $crate::internal_create_offer!(@object $object [$($key)+] (true) $($rest)*);
    };

    // Next value is `false`.
    (@object $object:ident ($($key:tt)+) (: false $($rest:tt)*) $copy:tt) => {
        $crate::internal_create_offer!(@object $object [$($key)+] (false) $($rest)*);
    };

    // Next value is an array.
    (@object $object:ident ($($key:tt)+) (: [$($array:tt)*] $($rest:tt)*) $copy:tt) => {
        // $crate::internal_create_offer!(@object $object [$($key)+] ($crate::internal_create_offer!([$($array)*])) $($rest)*);
        $crate::internal_create_offer!(@object $object [$($key)+] ($crate::internal_vec!(@array [] $($array)*)) $($rest)*);
    };

    // Next value is a nested object.
    (@object $object:ident ($($key:tt)+) (: {$($map:tt)*} $($rest:tt)*) $copy:tt) => {
        $crate::json_unexpected!($copy);
        // $crate::internal_create_offer!(@object $object [$($key)+] ($crate::internal_create_offer!(@object {$($map)*})) $($rest)*);
    };

    // (@object { $($tt:tt)+ }) => {
    //     serde_json::Value::Object({
    //         let mut map = serde_json::Map::new();
    //         $crate::internal_create_offer!(@object map () ($($tt)+) ($($tt)+));
    //         map
    //     })
    // };

    // Next value is an expression followed by comma.
    (@object $object:ident ($($key:tt)+) (: $value:expr , $($rest:tt)*) $copy:tt) => {
        $crate::internal_create_offer!(@object $object [$($key)+] ($value) ,  $($rest)*);
    };

    // Last value is an expression with no trailing comma.
    (@object $object:ident ($($key:tt)+) (: $value:expr ) $copy:tt) => {
        $crate::internal_create_offer!(@object $object [$($key)+] ($value));
    };

    // Missing value for last entry. Trigger a reasonable error message.
    (@object $object:ident ($($key:tt)+) (:) $copy:tt) => {
        // "unexpected end of macro invocation"
        $crate::internal_create_offer!();
    };

    // Missing colon and value for last entry. Trigger a reasonable error
    // message.
    (@object $object:ident ($($key:tt)+) () $copy:tt) => {
        // "unexpected end of macro invocation"
        $crate::internal_create_offer!();
    };

    // Misplaced colon. Trigger a reasonable error message.
    (@object $object:ident () (: $($rest:tt)*) ($colon:tt $($copy:tt)*)) => {
        // Takes no arguments so "no rules expected the token `:`".
        $crate::json_unexpected!($colon);
    };

    // Found a comma inside a key. Trigger a reasonable error message.
    (@object $object:ident ($($key:tt)*) (, $($rest:tt)*) ($comma:tt $($copy:tt)*)) => {
        // Takes no arguments so "no rules expected the token `,`".
        $crate::json_unexpected!($comma);
    };

    // Key is fully parenthesized. This avoids clippy double_parens false
    // positives because the parenthesization may be necessary here.
    (@object $object:ident () (($key:expr) : $($rest:tt)*) $copy:tt) => {
        $crate::internal_create_offer!(@object $object ($key) (: $($rest)*) (: $($rest)*));
    };

    // Refuse to absorb colon token into key expression.
    (@object $object:ident ($($key:tt)*) (: $($unexpected:tt)+) $copy:tt) => {
        $crate::json_expect_expr_comma!($($unexpected)+);
    };

    // Munch a token into the current key.
    (@object $object:ident ($($key:tt)*) ($tt:tt $($rest:tt)*) $copy:tt) => {
        $crate::internal_create_offer!(@object $object ($($key)* $tt) ($($rest)*) ($($rest)*));
    };
}

/// Array builder.
///
/// Invoked as: internal_vec!(@array [] $($tt)*)
#[macro_export]
#[doc(hidden)]
macro_rules! internal_vec {
    // Done with trailing comma.
    (@array [$($elems:expr,)*]) => {
        vec![$($elems,)*]
    };

    // Done without trailing comma.
    (@array [$($elems:expr),*]) => {
        vec![$($elems),*]
    };

    // Next element is `null`.
    (@array [$($elems:expr,)*] null $($rest:tt)*) => {
        $crate::internal_vec!(@array [$($elems,)* null] $($rest)*)
    };

    // Next element is `true`.
    (@array [$($elems:expr,)*] true $($rest:tt)*) => {
        $crate::internal_vec!(@array [$($elems,)* true] $($rest)*)
    };

    // Next element is `false`.
    (@array [$($elems:expr,)*] false $($rest:tt)*) => {
        $crate::internal_vec!(@array [$($elems,)* false] $($rest)*)
    };

    // Next element is an array.
    (@array [$($elems:expr,)*] [$($array:tt)*] $($rest:tt)*) => {
        $crate::internal_vec!(@array [$($elems,)* [$($array)*]] $($rest)*)
    };

    // Next element is a map.
    (@array [$($elems:expr,)*] {$($map:tt)*} $($rest:tt)*) => {
        $crate::internal_vec!(@array [$($elems,)* {$($map)*}] $($rest)*)
    };

    // Next element is an expression followed by comma.
    (@array [$($elems:expr,)*] $next:expr, $($rest:tt)*) => {
        $crate::internal_vec!(@array [$($elems,)* $next.to_string(),] $($rest)*)
    };


    // Last element is an expression with no trailing comma.
    (@array [$($elems:expr,)*] $last:expr) => {
        $crate::internal_vec!(@array [$($elems,)* $last.to_string()])
    };

    // Comma after the most recent element.
    (@array [$($elems:expr),*] , $($rest:tt)*) => {
        $crate::internal_vec!(@array [$($elems,)*] $($rest)*)
    };

    // Unexpected token after most recent element.
    (@array [$($elems:expr),*] $unexpected:tt $($rest:tt)*) => {
        $crate::json_unexpected!($unexpected)
    };
}

// // Used by old versions of Rocket.
// // Unused since https://github.com/rwf2/Rocket/commit/c74bcfd40a47b35330db6cafb88e4f3da83e0d17
// #[macro_export]
// #[doc(hidden)]
// macro_rules! json_internal_vec {
//     ($($content:tt)*) => {
//         vec![$($content)*]
//     };
// }

// #[macro_export]
// #[doc(hidden)]
// macro_rules! json_unexpected {
//     () => {};
// }

// #[macro_export]
// #[doc(hidden)]
// macro_rules! json_expect_key {
//     ( $other:expr ) => {
//         Err(anyhow::anyhow!("Unexpected key: {}", $other))
//     };
// }

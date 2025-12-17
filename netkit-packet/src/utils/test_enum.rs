//! Utility macros for testing enums.

/// Test the conversion between enum variants and their string representation.
#[macro_export]
macro_rules! test_enum_str {
    ($enum : ident, $($variant : ident => $str : literal),*  $(,)?) => {
        $(
            assert_eq!($enum::$variant.as_ref(), $str);
            assert_eq!($enum::from_str($str).unwrap(), $enum::$variant);
        )*
    }
}

/// Test the conversion between enum variants and their numerical representation.
#[macro_export]
macro_rules! test_enum_num {
    ($enum : ident : $prim : ident , $($variant : ident => $num : expr),*  $(,)?) => {
        $(
            assert_eq!(<$enum as Into<$prim>>::into($enum::$variant), $num);
            assert_eq!($enum::from($num as $prim), $enum::$variant);
        )*
    }
}

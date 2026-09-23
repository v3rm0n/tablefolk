pub mod cow;
pub mod permutation;
pub mod rand;
pub mod vector_arithmetic;

#[cfg(feature = "std")]
pub fn write_point<W: std::io::Write>(w: &mut W, affine: &str, p: &impl ark_ec::AffineRepr) -> std::io::Result<()> {
    if let Some((x,y)) = p.xy() {
        writeln!(w, "{}::new_unchecked(MontFp!(\"{:#?}\"), MontFp!(\"{:#?}\")),", affine, x, y )
    } else {
        writeln!(w, "{}::zero(),", affine)
    }
}

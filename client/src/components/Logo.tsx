interface LogoProps {
  className?: string;
  size?: number;
  /** Kept for compatibility with older call sites; the mark is always full-colour. */
  mono?: boolean;
  /** Kept for compatibility with older call sites; the mark is always full-colour. */
  ringColor?: string;
}

/** The full mark below ~24px collapses into mush, so small sizes get the
 *  compact cut: a wider aperture opening and heavier blade seams. */
const MARK_SRC = `${import.meta.env.BASE_URL}brand/threatlens-mark.svg`;
const MARK_COMPACT_SRC = `${import.meta.env.BASE_URL}brand/threatlens-mark-compact.svg`;
const COMPACT_BELOW = 24;

/**
 * Shared ThreatLens mark — a six-blade iris stopped down to a hexagonal
 * opening, with the focal point picked out in cyan.
 *
 * Vector, so shell chrome, login and setup all stay crisp at any size and on
 * any display density.
 */
export function Logo({ className, size = 24 }: LogoProps) {
  return (
    <img
      className={className}
      src={size < COMPACT_BELOW ? MARK_COMPACT_SRC : MARK_SRC}
      alt="ThreatLens"
      width={size}
      height={size}
      draggable={false}
      style={{
        width: size,
        height: size,
        objectFit: "contain",
      }}
    />
  );
}

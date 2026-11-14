/**
 * Environment lookup for the `THREATLENS_*` variable family.
 *
 * Every tunable is read through here so the prefix is defined in exactly one
 * place and a typo in a variable name fails the same way everywhere.
 */

/** Read `THREATLENS_<suffix>`, or undefined when unset or empty. */
export function env(suffix: string): string | undefined {
  const value = process.env[`THREATLENS_${suffix}`];
  return value !== undefined && value !== "" ? value : undefined;
}

/** True when the variable is set to a non-empty value. */
export function envIsSet(suffix: string): boolean {
  return env(suffix) !== undefined;
}

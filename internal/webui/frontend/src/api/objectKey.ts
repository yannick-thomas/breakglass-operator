/** objectKey identifies a namespaced BreakGlass object; names repeat across control namespaces. */
export function objectKey(o: { namespace: string; name: string }): string {
  return `${o.namespace}/${o.name}`;
}

/**
 * domId builds a unique HTML id for a namespaced object. Kubernetes names and
 * namespaces never contain '_', so it separates them without collisions and
 * keeps the id free of '/' for CSS selectors.
 */
export function domId(prefix: string, o: { namespace: string; name: string }): string {
  return `${prefix}-${o.namespace}_${o.name}`;
}

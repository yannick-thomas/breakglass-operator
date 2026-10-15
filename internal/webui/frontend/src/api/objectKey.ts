/** objectKey identifies a namespaced BreakGlass object; names repeat across control namespaces. */
export function objectKey(o: { namespace: string; name: string }): string {
  return `${o.namespace}/${o.name}`;
}

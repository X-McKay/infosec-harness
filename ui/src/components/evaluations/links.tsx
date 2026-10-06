import {
  createContext,
  useContext,
  type ComponentType,
  type ReactNode,
} from "react";

export type EvalLinkProps = {
  /** Always built by `reportPath` or `runPath` from a validated name or workflow ID. */
  href: string;
  className?: string;
  children: ReactNode;
  "aria-label"?: string;
};

const Anchor = ({ href, children, ...props }: EvalLinkProps) => (
  <a href={href} {...props}>
    {children}
  </a>
);

const LinkComponent = createContext<ComponentType<EvalLinkProps>>(Anchor);

/**
 * The evaluation views hold no router dependency. The app can supply a router-aware link
 * (e.g. wrapping TanStack Router's `Link`) here; the default is a plain anchor, which the SPA
 * fallback serves.
 */
export const EvaluationLinkProvider = LinkComponent.Provider;

export function EvalLink(props: EvalLinkProps) {
  const Component = useContext(LinkComponent);
  return <Component {...props} />;
}

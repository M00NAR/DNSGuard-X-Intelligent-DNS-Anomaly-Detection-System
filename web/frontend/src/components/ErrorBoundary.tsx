import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}
interface State {
  error: Error | null;
}

/** Catches render-time errors so one broken chart cannot blank the whole app. */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("DNSGuard-X UI error:", error, info);
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        <div className="banner error" role="alert">
          Something went wrong while displaying the results: {this.state.error.message}
        </div>
      );
    }
    return this.props.children;
  }
}

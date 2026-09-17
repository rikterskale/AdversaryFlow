import { QueryClientProvider } from "@tanstack/react-query";
import { createRoot } from "react-dom/client";

import { App } from "./app/App";
import { ErrorBoundary } from "./app/ErrorBoundary";
import { queryClient } from "./app/queryClient";
import "./styles/index.css";

const root = document.getElementById("root");
if (!root) throw new Error("AdversaryFlow could not find its application root.");

createRoot(root).render(
  <ErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </ErrorBoundary>,
);

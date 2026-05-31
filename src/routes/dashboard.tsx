import { createFileRoute } from "@tanstack/react-router";
import Dashboard from "@/pages/Dashboard";

export const Route = createFileRoute("/dashboard")({
  head: () => ({ meta: [{ title: "NetFast — Dashboard" }] }),
  component: Dashboard,
});

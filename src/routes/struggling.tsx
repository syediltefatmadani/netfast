import { createFileRoute } from "@tanstack/react-router";
import Struggling from "@/pages/Struggling";

export const Route = createFileRoute("/struggling")({
  head: () => ({ meta: [{ title: "NetFast — Pause" }] }),
  component: Struggling,
});

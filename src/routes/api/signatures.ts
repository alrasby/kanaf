import { createFileRoute } from "@tanstack/react-router";
import { refreshPart } from "@/lib/kanaf/refresh.server";

export const Route = createFileRoute("/api/signatures")({
  server: {
    handlers: {
      GET: ({ request }) => {
        const part = new URL(request.url).searchParams.get("part") ?? "";
        return refreshPart(part);
      },
    },
  },
});

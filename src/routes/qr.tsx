import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { Frame, TopBar } from "@/components/kanaf/chrome";
import { useI18n } from "@/lib/kanaf/i18n";
import { useKanaf } from "@/lib/kanaf/store";
import jsQR from "jsqr";

export const Route = createFileRoute("/qr")({ component: Qr });

function Qr() {
  const { t } = useI18n();
  const navigate = useNavigate();
  const shell = useKanaf((s) => s.shell);
  const videoRef = useRef<HTMLVideoElement>(null);
  const [live, setLive] = useState(false);
  const [note, setNote] = useState("");
  const [text, setText] = useState("");
  const stopRef = useRef<(() => void) | null>(null);

  useEffect(() => () => stopRef.current?.(), []);

  function stop() {
    stopRef.current?.();
    stopRef.current = null;
    setLive(false);
  }

  async function start() {
    stop();
    setText("");
    setNote("");
    if (shell === "android") {
      const allowed = await new Promise<boolean>((resolve) => {
        let settled = false;
        const finish = (ok: boolean) => {
          if (settled) return;
          settled = true;
          resolve(ok);
        };
        (window as Window & { __kanafCamera?: (ok: boolean) => void }).__kanafCamera = finish;
        (window as Window & { KanafNative?: { askCamera?: () => void } }).KanafNative?.askCamera?.();
        window.setTimeout(() => finish(false), 20000);
      });
      if (!allowed) {
        setNote(t.cleanWeb);
        return;
      }
    }
    const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
    const video = videoRef.current;
    if (!video) {
      stream.getTracks().forEach((track) => track.stop());
      return;
    }
    video.srcObject = stream;
    video.muted = true;
    await video.play();
    setLive(true);
    let timer = 0;
    const canvas = document.createElement("canvas");
    const Detector = (window as Window & { BarcodeDetector?: new (opts: { formats: string[] }) => { detect: (source: HTMLVideoElement) => Promise<{ rawValue?: string }[]> } }).BarcodeDetector;
    const detector = Detector ? new Detector({ formats: ["qr_code"] }) : null;
    const tick = async () => {
      if (!video.videoWidth) {
        timer = window.setTimeout(tick, 200);
        return;
      }
      let found = "";
      try {
        if (detector) {
          const codes = await detector.detect(video);
          found = codes[0]?.rawValue || "";
        } else {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          const ctx = canvas.getContext("2d", { willReadFrequently: true });
          if (ctx) {
            ctx.drawImage(video, 0, 0);
            const frame = ctx.getImageData(0, 0, canvas.width, canvas.height);
            found = jsQR(frame.data, frame.width, frame.height)?.data || "";
          }
        }
      } catch {
        found = "";
      }
      if (found) {
        setText(found);
        setNote("");
        stop();
        return;
      }
      timer = window.setTimeout(tick, 350);
    };
    stopRef.current = () => {
      window.clearTimeout(timer);
      stream.getTracks().forEach((track) => track.stop());
      video.srcObject = null;
    };
    timer = window.setTimeout(tick, 350);
  }

  return (
    <Frame>
      <TopBar title={t.qrTitle} />
      <p className="mb-3 text-sm leading-relaxed text-muted">{t.qrLead}</p>
      <video ref={videoRef} className="mb-3 aspect-[3/4] w-full rounded-xl bg-ink object-cover" playsInline />
      <button type="button" className="h-11 w-full rounded-xl bg-teal text-sm font-semibold text-teal-ink" onClick={() => void (live ? stop() : start().catch(() => setNote(t.failed)))}>
        {live ? t.qrStop : t.qrStart}
      </button>
      {note ? <p className="mt-3 text-sm text-gold">{note}</p> : null}
      {text ? (
        <div className="mt-3">
          <p className="break-all text-sm" dir="ltr">
            {text}
          </p>
          <button
            type="button"
            className="mt-2 h-11 w-full rounded-xl bg-gold text-sm font-semibold text-ink"
            onClick={() => void navigate({ to: "/phish", search: { text } })}
          >
            {t.scanLink}
          </button>
        </div>
      ) : null}
    </Frame>
  );
}

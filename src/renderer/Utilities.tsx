import { useEffect } from "react";

export type EffectDestructor = () => void;

export function useAsyncEffect(
  callback: () => Promise<EffectDestructor | void>,
  dependencies?: unknown[],
): void {
  useEffect(() => {
    let destructor: EffectDestructor | null = null;
    let destroy = false;
    callback()
      .then((result) => {
        if (result) {
          if (destroy) {
            result();
          } else {
            destructor = result;
          }
        } else {
          destructor = null;
          destroy = false;
        }
      })
      .catch((error) => {
        destructor = null;
        destroy = false;
        console.error(error);
      });
    return () => {
      if (destructor) {
        destructor();
      } else {
        destroy = true;
      }
    };
  }, dependencies);
}

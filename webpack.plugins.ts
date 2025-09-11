import type { Configuration } from "webpack";

import type IForkTsCheckerWebpackPlugin from "fork-ts-checker-webpack-plugin";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const ForkTsCheckerWebpackPlugin: typeof IForkTsCheckerWebpackPlugin = require("fork-ts-checker-webpack-plugin");

export const plugins: NonNullable<Configuration["plugins"]> = [
  new ForkTsCheckerWebpackPlugin({
    logger: "webpack-infrastructure",
  }),
];

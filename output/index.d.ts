import "reflect-metadata";
import type { AppContext, AppPlugin } from "@tsdiapi/server";
export { CryptoService } from "./crypto.service.js";
export type PluginOptions = {};
declare class App implements AppPlugin {
    name: string;
    config: PluginOptions;
    context: AppContext;
    constructor(config?: PluginOptions);
    onInit(ctx: AppContext): Promise<void>;
}
export default function createPlugin(config?: PluginOptions): App;
//# sourceMappingURL=index.d.ts.map
import "reflect-metadata";
import type { AppContext, AppPlugin } from "@tsdiapi/server";
export type PluginOptions = {};
declare class App implements AppPlugin {
    name: string;
    config: PluginOptions;
    context: AppContext;
    services: AppPlugin['services'];
    constructor(config?: PluginOptions);
    onInit(ctx: AppContext): Promise<void>;
}
export default function createPlugin(config?: PluginOptions): App;
export {};
//# sourceMappingURL=index.d.ts.map
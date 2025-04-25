import "reflect-metadata";
import type { AppContext, AppPlugin } from "@tsdiapi/server";
import { CryptoService } from "./crypto.service.js";
export { CryptoService } from "./crypto.service.js";
export type PluginOptions = {
}

class App implements AppPlugin {
    name = 'tsdiapi-crypto';
    config: PluginOptions;
    context: AppContext;
    services: AppPlugin['services'] = [];
    constructor(config?: PluginOptions) {
        this.config = { ...config };
    }
    async onInit(ctx: AppContext) {
        this.context = ctx;
        this.services.push(CryptoService);
    }
}

export default function createPlugin(config?: PluginOptions) {
    return new App(config);
}
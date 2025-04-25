import "reflect-metadata";
import { CryptoService } from "./crypto.service.js";
class App {
    name = 'tsdiapi-crypto';
    config;
    context;
    services = [];
    constructor(config) {
        this.config = { ...config };
    }
    async onInit(ctx) {
        this.context = ctx;
        this.services.push(CryptoService);
    }
}
export default function createPlugin(config) {
    return new App(config);
}
//# sourceMappingURL=index.js.map
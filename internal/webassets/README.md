# 随程序打包的浏览器脚本

管理员页面使用固定的 SortableJS 与 QRCode.js 源码，不在浏览器中向 CDN 下载可执行脚本。脚本和 MIT 许可证嵌入 Go 程序，离线包与容器无需额外复制静态资源目录。国旗图片仍来自 flagcdn.com；本改动不代表整个面板完全离线。

- SortableJS 1.15.7：[上游固定提交](https://github.com/SortableJS/Sortable/tree/031649b8116565e02419e8aa2d252d7d8c82b9da)。
- QRCode.js：[上游固定提交](https://github.com/davidshimjs/qrcodejs/tree/04f46c6a0708418cb7b96fc563eacae0fbf77674)。按提交固定，不依赖 CDN 的版本别名。
- `vendor/manifest.json` 记录原文件地址、SHA-256、浏览器 SRI 与许可证。JS 文件保持上游原始字节，文件名包含内容摘要。

`/assets/vendor/` 只提供已嵌入的脚本和许可证，支持 GET/HEAD、ETag 与长期缓存，不开放目录列表或本地文件。反代应把此路径转发给面板。

升级时从明确版本或提交获取源码，保留许可证，检查变更，重新生成摘要、文件名和模板中的 SRI，再运行 Go 测试与 `tests/browser-assets-ui.cjs`。不要覆盖同名缓存文件。脚本来源与完整性可追溯不等于已经完成第三方库的全面安全审计。

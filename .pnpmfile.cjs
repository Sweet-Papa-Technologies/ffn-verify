// pnpm hooks for this workspace.
module.exports = {
  hooks: {
    // @fofonet/verify-business is published with door-core bundled in. Its
    // devDependencies (workspace packages and build tools) and scripts mean
    // nothing on npm, so `pnpm pack` / `pnpm publish` leave them out.
    beforePacking(pkg) {
      if (pkg.name === '@fofonet/verify-business') {
        delete pkg.devDependencies;
        delete pkg.scripts;
      }
      return pkg;
    },
  },
};

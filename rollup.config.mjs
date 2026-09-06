import commonjs from '@rollup/plugin-commonjs';
import nodeResolve from '@rollup/plugin-node-resolve';
import typescript from '@rollup/plugin-typescript';

export default {
  input: 'src/main.ts',
  output: {
    dir: '.',
    format: 'cjs',
    sourcemap: true,
    exports: 'default',
  },
  external: ['obsidian'],
  plugins: [
    nodeResolve({ browser: true }),
    commonjs(),
    typescript(),
  ],
  onwarn: (warning, warn) => {
    // Ignore nodeResolve warnings about missing module runs
    if (warning.code === 'MODULE_LEVEL_DIRECTIVE') return;
    if (warning.code === 'THIS_IS_UNDEFINED') return;
    if (warning.code === 'CIRCULAR_DEPENDENCY') return;
    warn(warning);
  }
};

const path = require('path');
const webpack = require('webpack')

module.exports = {
  mode: "production",
  entry: "./lib/index.js",
  devtool: "source-map",
  output: {
    filename: 'eudgc.sdk.min.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'EUDGC',
    libraryTarget: 'umd',
  },
  target: 'web',

  optimization: {
    minimize: true
  },
  node: {
    net: 'empty',
  },
  plugins: [
    new webpack.ProvidePlugin({
      process: 'process/browser'
    })
  ],
};
/*!
 * Copyright (c) 2021 PathCheck Foundation. All rights reserved.
 */
'use strict';

// translate `main.js` to CommonJS
require = require('esm')(module);

const main = require('./main.js');
module.exports = main;
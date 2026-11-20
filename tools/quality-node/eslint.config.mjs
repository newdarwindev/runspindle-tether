export default [
  {
    files: ["**/*.js", "**/*.mjs", "**/*.cjs"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        console: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        URL: "readonly",
        process: "readonly",
        Buffer: "readonly",
        structuredClone: "readonly",
      },
    },
    rules: {
      "no-unused-vars": ["error", { args: "none", caughtErrors: "none" }],
      "no-undef": "error",
      "constructor-super": "error",
      "no-unreachable": "error",
      "valid-typeof": "error",
    },
  },
  {
    files: ["**/*.cjs"],
    languageOptions: {
      sourceType: "commonjs",
      globals: {
        __dirname: "readonly",
        document: "readonly",
        HTMLDetailsElement: "readonly",
        scrollX: "readonly",
        scrollY: "readonly",
        getComputedStyle: "readonly",
        devicePixelRatio: "readonly",
        innerWidth: "readonly",
        outerWidth: "readonly",
        innerHeight: "readonly",
        outerHeight: "readonly",
        visualViewport: "readonly",
      },
    },
  },
];

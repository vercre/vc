import typescript from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';
import es6Import from 'eslint-plugin-import';
import jsxA11y from 'eslint-plugin-jsx-a11y';
import react from 'eslint-plugin-react';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import globals from 'globals';

// To use eslint flat config:
//   1. Set "type": "module" in package.json
//   2. In ESLint plugin, ensure you are using the Pre-Release version
//   3. Check 'Experimental: Use Flat Config' in VSCode settings

export default [
    'eslint:recommended',
    {
        env: {
            browser: true,
            node: true,
        },
        files: ['**/*.{js,jsx,ts,tsx}'],
        plugins: {
            '@typescript-eslint': typescript,
            import: es6Import,
            'jsx-a11y': jsxA11y,
            react,
            'react-hooks': reactHooks,
            'react-refresh': reactRefresh,
            typescript,
        },
        languageOptions: {
            parser: tsParser,
            parserOptions: {
                ecmaFeatures: {
                    jsx: true,
                    modules: true,
                },
                ecmaVersion: 'latest',
            },
            globals: {
                JSX: 'readonly',
                ...globals.browser,
            },
        },
        rules: {
            ...typescript.configs['eslint-recommended'].rules,
            ...typescript.configs['recommended'].rules,
            ...jsxA11y.configs.recommended.rules,
            ...react.configs.recommended.rules,
            ...reactHooks.configs.recommended.rules,
            'react-hooks/exhaustive-deps': 'error',
            'react/prop-types': 0,
            'react/react-in-jsx-scope': 0,
            camelcase: ['error'],
            'prefer-template': 'error',
            'prefer-const': 'error',
            eqeqeq: ['error', 'smart'],
            'import/order': [
                'warn',
                {
                    groups: [
                        'builtin',
                        'external',
                        'internal',
                    ],
                    pathGroups: [
                        {
                            pattern: 'react',
                            group: 'external',
                            position: 'before'
                        },
                    ],
                    pathGroupsExcludedImportTypes: [
                        'react'
                    ],
                    'newlines-between': 'always',
                    alphabetize: {
                        order: 'asc',
                        caseInsensitive: true
                    },
                },
            ],
            'no-restricted-imports': [
                'error',
                {
                    patterns: ['@mui/*/*/*', '!@mui/material/test-utils/*']
                }
            ],
            'react-refresh/only-export-components': 'warn',
        },
    },
];


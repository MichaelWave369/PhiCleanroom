import assert from 'node:assert/strict'
import test from 'node:test'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createElement } from 'react'
import { renderToString } from 'react-dom/server'
import { createServer } from 'vite'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')

test('the actual React App renders instead of producing a blank screen', async () => {
  // A bundle can build successfully while JSX throws only when a component
  // renders. Loading App through Vite's JSX transformer catches this class
  // of issue without requiring any private vault data or live network calls.
  const vite = await createServer({
    root,
    configFile: resolve(root, 'vite.config.js'),
    server: { middlewareMode: true },
    appType: 'custom',
    logLevel: 'silent',
  })
  try {
    const { default: App } = await vite.ssrLoadModule('/src/App.jsx')
    const markup = renderToString(createElement(App))

    assert.match(markup, /Original code/)
    assert.match(markup, /Proven behavior/)
    assert.match(markup, /Evidence Vault v2/)
    assert.match(markup, /PHICLEANROOM \/ GATE EXPLORER/)
    assert.match(markup, /site-navigation/)
    assert.ok(markup.length > 10_000, 'expected the full page, not an empty root')
  } finally {
    await vite.close()
  }
})

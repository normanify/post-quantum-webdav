import { vi } from 'vitest';

vi.mock('obsidian', () => {
  class Plugin {}
  class PluginSettingTab {}
  class Setting {}
  class App {}
  class TFile {}
  class TAbstractFile {}
  class DataAdapter {}
  class Notice {}
  const requestUrl = vi.fn();
  return { Plugin, PluginSettingTab, Setting, App, TFile, TAbstractFile, DataAdapter, Notice, requestUrl };
});

if (!globalThis.window) {
  (globalThis as Record<string, unknown>).window = globalThis;
}
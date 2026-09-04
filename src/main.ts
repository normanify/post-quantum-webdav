import { Plugin } from 'obsidian';

export default class PqcWebdavPlugin extends Plugin {
  async onload() {
    console.log('PQC WebDAV Sync loaded');
  }

  onunload() {
    console.log('PQC WebDAV Sync unloaded');
  }
}

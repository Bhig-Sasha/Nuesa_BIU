const fs = require('fs').promises;
const path = require('path');

class FileCleanup {
    constructor() {
        this.uploadDirs = [
            'uploads/events',
            'uploads/articles',
            'uploads/profiles',
            'uploads/resources'
        ];
    }

    async cleanupOrphanedFiles() {
        for (const dir of this.uploadDirs) {
            try {
                const files = await fs.readdir(dir);
                
                for (const file of files) {
                    const filePath = path.join(dir, file);
                    const stats = await fs.stat(filePath);
                    
                    // Delete files older than 30 days that aren't referenced in database
                    const daysOld = (Date.now() - stats.mtimeMs) / (1000 * 60 * 60 * 24);
                    
                    if (daysOld > 30) {
                        await fs.unlink(filePath);
                        console.log(`Deleted orphaned file: ${filePath}`);
                    }
                }
            } catch (error) {
                if (error.code !== 'ENOENT') {
                    console.error(`Error cleaning up ${dir}:`, error.message);
                }
            }
        }
    }
}

module.exports = new FileCleanup();
import 'dotenv/config';
import { readdirSync } from 'fs';
import { basename, dirname } from 'path';
import { Sequelize, DataTypes } from 'sequelize';
import { fileURLToPath } from 'url';
import configuration from '../config/config.js';

const env = process.env.NODE_ENV || 'production';
const config = configuration[env] || configuration['production'];

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const db = {};
const sequelize = new Sequelize(config);

const initializeModels = async () => {
  try {
    const files = readdirSync(__dirname)
      .filter(
        (file) => file.indexOf('.') !== 0
          && file !== basename(__filename)
          && file.slice(-3) === '.js',
      );

    for (const file of files) {
      const model = await import(`./${file}`);
      const namedModel = model.default(sequelize, DataTypes);
      db[namedModel.name] = namedModel;
    }

    // Set up associations
    Object.keys(db).forEach((modelName) => {
      if (db[modelName].associate) {
        db[modelName].associate(db);
      }
    });

    db.sequelize = sequelize;
    db.Sequelize = Sequelize;

    return db;
  } catch (error) {
    console.error('Error loading models:', error);
    throw error;
  }
};

export default initializeModels;

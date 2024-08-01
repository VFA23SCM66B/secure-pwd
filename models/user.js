'use strict';
import { Model } from 'sequelize';

export default (sequelize, DataTypes) => {
  class User extends Model {
    // static associate(models) {
    //   User.hasMany(models.UserPassword, { foreignKey: 'ownerUserId' });
    // }
  }
  User.init({
    name: DataTypes.STRING,
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        isEmail: {
          msg: "Please write a valid email address"
        }
      }
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        len: {
          args: [8, 200],
          msg: "Password must be between 8 characters to 200 characters"
        }
      }
    },
    encryption_key: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        len: {
          args: [8, 200],
          msg: "Encryption key must be between 8 characters to 200 characters"
        }
      }
    }
  }, {
    sequelize,
    modelName: 'User',
  });
  return User;
};

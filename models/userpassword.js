'use strict';
const { Model, DataTypes } = require('sequelize');

module.exports = (sequelize) => {
  class UserPassword extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // Define association to User model
      UserPassword.belongsTo(models.User, {
        foreignKey: 'userId',
        as: 'user', // Alias for the association
        onDelete: 'CASCADE', // Action when the associated user is deleted
      });

      // Define association to SharedPassword model
      UserPassword.hasMany(models.SharedPassword, {
        foreignKey: 'source_password_id',
        as: 'sharedPasswords', // Alias for the association
      });
    }
  }

  UserPassword.init({
    userId: {
      type: DataTypes.UUID,
      allowNull: false, // Ensure userId is always provided
    },
    url: {
      type: DataTypes.STRING,
      allowNull: false, // Ensure URL is always provided
    },
    username: {
      type: DataTypes.STRING,
      allowNull: false, // Ensure username is always provided
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false, // Ensure password is always provided
    },
    label: {
      type: DataTypes.STRING,
      allowNull: false, // Ensure label is always provided
    },
    weak_encryption: {
      type: DataTypes.BOOLEAN,
      defaultValue: false, // Default value for weak_encryption
    },
  }, {
    sequelize,
    modelName: 'UserPassword',
  });

  return UserPassword;
};

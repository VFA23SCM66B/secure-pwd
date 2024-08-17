'use strict';
const { Model, DataTypes } = require('sequelize');

module.exports = (sequelize) => {
  class SharedPassword extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // Define association to User model for both ownerUserId and sharedByUserId
      SharedPassword.belongsTo(models.User, {
        foreignKey: 'ownerUserId',
        as: 'ownerUser', // Alias for the association
        onDelete: 'SET NULL', // Action when the associated owner user is deleted
      });

      SharedPassword.belongsTo(models.User, {
        foreignKey: 'sharedByUserId',
        as: 'sharedByUser', // Alias for the association
        onDelete: 'SET NULL', // Action when the associated user who shared is deleted
      });

      // Define association to UserPassword model for source_password_id
      SharedPassword.belongsTo(models.UserPassword, {
        foreignKey: 'source_password_id',
        as: 'sourcePassword', // Alias for the association
        onDelete: 'SET NULL', // Action when the associated source password is deleted
      });
    }
  }

  SharedPassword.init({
    ownerUserId: {
      type: DataTypes.UUID,
      allowNull: true,
    },
    label: {
      type: DataTypes.STRING,
      allowNull: false, // Ensure that label is always provided
    },
    url: {
      type: DataTypes.STRING,
      allowNull: false, // Ensure that URL is always provided
    },
    username: {
      type: DataTypes.STRING,
      allowNull: false, // Ensure that username is always provided
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false, // Ensure that password is always provided
    },
    sharedByUserId: {
      type: DataTypes.UUID,
      allowNull: true,
    },
    weak_encryption: {
      type: DataTypes.BOOLEAN,
      defaultValue: false, // Default value for weak_encryption
    },
    source_password_id: {
      type: DataTypes.UUID,
      allowNull: true,
    },
    expiry_date: {
      type: DataTypes.DATE,
      allowNull: true,
    },
  }, {
    sequelize,
    modelName: 'SharedPassword',
  });

  return SharedPassword;
};

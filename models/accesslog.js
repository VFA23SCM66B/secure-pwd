import { Model, DataTypes } from 'sequelize';

class AccessLog extends Model {
  /**
   * Helper method for defining associations.
   * This method is not a part of Sequelize lifecycle.
   * The `models/index` file will call this method automatically.
   */
  static associate(models) {
    // Define association to User model for both userId and recipientUserId
    AccessLog.belongsTo(models.User, {
      foreignKey: 'userId',
      as: 'user', // Alias for the association
      onDelete: 'SET NULL', // Action when the associated user is deleted
    });

    AccessLog.belongsTo(models.User, {
      foreignKey: 'recipientUserId',
      as: 'recipientUser', // Alias for the association
      onDelete: 'SET NULL', // Action when the associated recipient user is deleted
    });

    // Define association to UserPassword model for passwordId
    AccessLog.belongsTo(models.UserPassword, {
      foreignKey: 'passwordId',
      as: 'password', // Alias for the association
      onDelete: 'SET NULL', // Action when the associated password is deleted
    });
  }
}

// Initialize the model
const defineAccessLog = (sequelize) => {
  AccessLog.init({
    action: {
      type: DataTypes.STRING,
      allowNull: false, // Ensure that action is always provided
    },
    userId: {
      type: DataTypes.UUID,
      allowNull: true,
    },
    recipientUserId: {
      type: DataTypes.UUID,
      allowNull: true,
    },
    passwordId: {
      type: DataTypes.UUID,
      allowNull: true,
    },
    timestamp: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW, // Default value for timestamp
    },
  }, {
    sequelize,
    modelName: 'AccessLog',
  });

  return AccessLog;
};

export default defineAccessLog;

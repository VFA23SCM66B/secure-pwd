import { Model, DataTypes } from 'sequelize';

class SharedPassword extends Model {
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

// Initialize the model
const defineSharedPassword = (sequelize) => {
  SharedPassword.init({
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    ownerUserId: {
      type: DataTypes.INTEGER,
      allowNull: true,
    },
    label: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    url: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    username: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    sharedByUserId: {
      type: DataTypes.INTEGER,
      allowNull: true,
    },
    weak_encryption: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    source_password_id: {
      type: DataTypes.INTEGER,
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

export default defineSharedPassword;

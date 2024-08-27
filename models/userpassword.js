import { Model, DataTypes } from 'sequelize';

class UserPassword extends Model {
  static associate(models) {
    // Define association to User model
    UserPassword.belongsTo(models.User, {
      foreignKey: 'userId',
      as: 'user',
      onDelete: 'CASCADE',
    });

    // Define association to SharedPassword model
    UserPassword.hasMany(models.SharedPassword, {
      foreignKey: 'source_password_id',
      as: 'sharedPasswords',
    });
  }
}

// Initialize the model
const defineUserPassword = (sequelize) => {
  UserPassword.init({
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    userId: {
      type: DataTypes.INTEGER,
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
    label: {
      type: DataTypes.STRING,
      allowNull: false,
    },
  }, {
    sequelize,
    modelName: 'UserPassword',
  });

  return UserPassword;
};

export default defineUserPassword;

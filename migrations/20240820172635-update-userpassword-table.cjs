'use strict';

module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.changeColumn('UserPasswords', 'userId', {
      type: Sequelize.INTEGER,
      allowNull: false,
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.changeColumn('UserPasswords', 'userId', {
      type: Sequelize.UUID,
      allowNull: false,
    });
  },
};

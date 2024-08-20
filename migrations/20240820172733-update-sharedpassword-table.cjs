'use strict';

module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.changeColumn('SharedPasswords', 'ownerUserId', {
      type: Sequelize.INTEGER,
      allowNull: true,
    });
    await queryInterface.changeColumn('SharedPasswords', 'sharedByUserId', {
      type: Sequelize.INTEGER,
      allowNull: true,
    });
    await queryInterface.changeColumn('SharedPasswords', 'source_password_id', {
      type: Sequelize.INTEGER,
      allowNull: true,
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.changeColumn('SharedPasswords', 'ownerUserId', {
      type: Sequelize.UUID,
      allowNull: true,
    });
    await queryInterface.changeColumn('SharedPasswords', 'sharedByUserId', {
      type: Sequelize.UUID,
      allowNull: true,
    });
    await queryInterface.changeColumn('SharedPasswords', 'source_password_id', {
      type: Sequelize.UUID,
      allowNull: true,
    });
  },
};

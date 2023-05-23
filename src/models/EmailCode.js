const { DataTypes } = require('sequelize');
const sequelize = require('../utils/connection');

const EmailCode = sequelize.define('emailcode', {
    code: {
        type: DataTypes.STRING,
        allowNull: false
    },
    //userid
});

module.exports = EmailCode;
#!/usr/bin/env python3
"""
Script to recreate the material table in the vms_pro database
"""
from app import app, db, Material
import logging

logging.basicConfig(level=logging.INFO)

def recreate_material_table():
    with app.app_context():
        try:
            # Drop the material table if it exists
            logging.info("Dropping existing material table...")
            db.session.execute(db.text('DROP TABLE IF EXISTS material'))
            db.session.commit()
            logging.info("Material table dropped successfully")
            
            # Create the material table with correct structure
            logging.info("Creating new material table...")
            db.create_all()
            logging.info("Material table created successfully")
            
            # Verify the table structure
            result = db.session.execute(db.text("DESCRIBE material"))
            logging.info("Material table structure:")
            for row in result:
                logging.info(f"  {row}")
            
            logging.info("Material table has been successfully recreated!")
            logging.info("Columns: id, visitor_id, visitor_code, name, type, make, serial_number")
            
        except Exception as e:
            logging.error(f"Error recreating material table: {e}")
            db.session.rollback()
            raise

if __name__ == "__main__":
    recreate_material_table()

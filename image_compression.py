from PIL import Image
from io import BytesIO
import logging

def compress_visitor_photo(binary_data, target_size_kb):
    """
    Compress visitor photo to target size
    
    Args:
        binary_data: Original image binary data
        target_size_kb: Target size in KB (required)
    
    Returns:
        Compressed image binary data
    """
    try:
        # Open image from binary data
        image = Image.open(BytesIO(binary_data))
        
        # Convert to RGB if necessary
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Compress with quality reduction until target size is reached
        quality = 85
        target_bytes = target_size_kb * 1024
        
        while quality >= 25:  # Minimum quality threshold
            output = BytesIO()
            image.save(output, format='JPEG', quality=quality, optimize=True)
            compressed_data = output.getvalue()
            
            if len(compressed_data) <= target_bytes:
                logging.info(f"Image compressed to {len(compressed_data)/1024:.1f}KB at quality {quality}")
                return compressed_data
            
            # Reduce quality
            quality -= 10
        
        # If we still haven't reached target size, use minimum quality
        output = BytesIO()
        image.save(output, format='JPEG', quality=25, optimize=True)
        compressed_data = output.getvalue()
        logging.info(f"Image compressed to minimum quality: {len(compressed_data)/1024:.1f}KB")
        return compressed_data
        
    except Exception as e:
        logging.error(f"Error compressing image: {e}")
        # Return original data if compression fails
        return binary_data
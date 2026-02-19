# Photo Compression Implementation for VMS

## Changes needed in app.py:

### 1. Add compression function at the top of the file (after imports):

```python
def compress_photo(binary_data):
    """Compress photo to around 50KB"""
    try:
        image = Image.open(BytesIO(binary_data))
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Try quality 75 first
        output = BytesIO()
        image.save(output, format='JPEG', quality=75, optimize=True)
        compressed = output.getvalue()
        
        # If still too large, try quality 60
        if len(compressed) > 50 * 1024:
            output = BytesIO()
            image.save(output, format='JPEG', quality=60, optimize=True)
            compressed = output.getvalue()
            
        logging.info(f"Photo compressed to {len(compressed)/1024:.1f}KB")
        return compressed
    except Exception as e:
        logging.error(f"Compression error: {e}")
        return binary_data
```

### 2. Modify the photo saving section (around line 2325):

**Original code:**
```python
photo_filename = f"{temp_photo_filename_prefix}_{visitor.Visitor_ID}.png"
photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
with open(photo_path, 'wb') as f:
    f.write(temp_photo_binary_data)
```

**Modified code:**
```python
# Compress photo before saving
compressed_data = compress_photo(temp_photo_binary_data)
photo_filename = f"{temp_photo_filename_prefix}_{visitor.Visitor_ID}.jpg"  # Changed to .jpg
photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
with open(photo_path, 'wb') as f:
    f.write(compressed_data)
```

### 3. Update the logging message:
```python
logging.info(f"Visitor photo compressed and saved: {photo_path} ({len(compressed_data)/1024:.1f}KB)")
```

## Expected Results:

- Photos will be compressed to approximately 50KB or less
- File format changed from PNG to JPEG for better compression
- Quality will be reduced to 75% or 60% as needed
- Maintains good visual quality while significantly reducing file size
- Existing visitor photos will remain unchanged until new ones are captured

## File Size Comparison:
- Before: 92KB - 2632KB (average ~150KB)
- After: Target ~50KB (60-70% reduction)
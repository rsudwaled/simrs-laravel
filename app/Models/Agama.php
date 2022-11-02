<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Agama extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'mt_agama';
    protected $primaryKey = 'ID';
    public $incrementing = false;
    protected $keyType = 'string';
}

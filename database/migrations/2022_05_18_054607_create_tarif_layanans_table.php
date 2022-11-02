<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('tarif_layanans', function (Blueprint $table) {
            $table->id();
            $table->string('kodetarif')->unique();
            $table->string('nosk')->nullable();
            $table->string('namatarif');
            $table->string('tarifkelompokid')->nullable();
            $table->string('tarifvclaimid')->nullable();
            $table->string('keterangan')->nullable();
            $table->string('status');
            $table->string('userid');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('tarif_layanans');
    }
};
